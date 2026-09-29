// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TLS for the proxy's port, terminated in the proxy behind a TCP-passthrough
//! load balancer. The certificate is publicly trusted, since browsers read
//! `/info` on the same port: an exportable ACM certificate, re-exported as ACM
//! renews it, or PEM files.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tracing::info;
use tracing::warn;

use crate::metrics::ProxyMetrics;

/// ACM renews a certificate 45 days before it expires; the proxy picks the
/// renewal up on its next reload.
const RELOAD_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// The AWS SDK sets no read timeout, so a stalled export would otherwise hold
/// up startup or every later reload.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub enum CertSource {
    /// An exportable ACM certificate, exported with the task role.
    Acm { arn: String },
    /// A PEM certificate chain, leaf first, and its PEM private key.
    Files { cert: PathBuf, key: PathBuf },
}

/// The certificate the proxy serves, replaced in place by a successful reload.
#[derive(Debug)]
pub struct ServerCert {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ServerCert {
    pub async fn load(source: &CertSource, metrics: &ProxyMetrics) -> Result<Arc<Self>> {
        let key = load_certified_key(source).await?;
        record_expiry(&key, metrics)?;
        Ok(Arc::new(Self {
            current: RwLock::new(Arc::new(key)),
        }))
    }

    /// Keeps the current certificate when the load fails.
    async fn reload(&self, source: &CertSource, metrics: &ProxyMetrics) -> Result<()> {
        let key = load_certified_key(source).await?;
        record_expiry(&key, metrics)?;
        *self.current.write().expect("certificate lock poisoned") = Arc::new(key);
        Ok(())
    }

    pub async fn reload_forever(self: Arc<Self>, source: CertSource, metrics: Arc<ProxyMetrics>) {
        loop {
            tokio::time::sleep(RELOAD_INTERVAL).await;
            match self.reload(&source, &metrics).await {
                Ok(()) => info!("Reloaded the TLS certificate."),
                Err(e) => {
                    metrics.tls_cert_reload_failures.inc();
                    warn!(
                        error = %format!("{e:#}"),
                        "TLS certificate reload failed; serving the current one."
                    );
                }
            }
        }
    }
}

impl ResolvesServerCert for ServerCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.current
                .read()
                .expect("certificate lock poisoned")
                .clone(),
        )
    }
}

pub fn server_config(cert: Arc<ServerCert>) -> Result<rustls::ServerConfig> {
    Ok(rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(cert))
}

async fn load_certified_key(source: &CertSource) -> Result<CertifiedKey> {
    let (chain, key) = match source {
        CertSource::Acm { arn } => tokio::time::timeout(EXPORT_TIMEOUT, export_from_acm(arn))
            .await
            .context("the ACM certificate export timed out")??,
        CertSource::Files { cert, key } => {
            let chain = CertificateDer::pem_file_iter(cert)
                .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
                .with_context(|| format!("read TLS certificate chain {}", cert.display()))?;
            let key = PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("read TLS private key {}", key.display()))?;
            (chain, key)
        }
    };
    anyhow::ensure!(!chain.is_empty(), "the TLS certificate chain is empty");
    CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .context("the TLS private key does not load or does not match the certificate")
}

async fn export_from_acm(
    arn: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // arn:aws:acm:<region>:<account>:certificate/<id>
    let region = arn
        .split(':')
        .nth(3)
        .filter(|region| !region.is_empty())
        .with_context(|| format!("no region in certificate ARN {arn}"))?;
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;
    let passphrase = hex::encode(rand::random::<[u8; 32]>());
    let exported = aws_sdk_acm::Client::new(&aws_config)
        .export_certificate()
        .certificate_arn(arn)
        .passphrase(aws_sdk_acm::primitives::Blob::new(passphrase.as_bytes()))
        .send()
        .await
        .with_context(|| format!("export ACM certificate {arn}"))?;

    let mut pem = exported
        .certificate()
        .context("ACM export returned no certificate")?
        .to_string();
    // The chain excludes the leaf, which has to come first.
    pem.push('\n');
    pem.push_str(exported.certificate_chain().unwrap_or_default());
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parse the exported ACM certificate chain")?;
    let key = decrypt_private_key(
        exported
            .private_key()
            .context("ACM export returned no private key")?,
        passphrase.as_bytes(),
    )?;
    Ok((chain, key))
}

fn decrypt_private_key(pem: &str, passphrase: &[u8]) -> Result<PrivateKeyDer<'static>> {
    use pkcs8::der::Decode;

    let (label, der) =
        pkcs8::der::pem::decode_vec(pem.as_bytes()).context("parse the private key PEM")?;
    let key_der = match label {
        "ENCRYPTED PRIVATE KEY" => pkcs8::EncryptedPrivateKeyInfo::from_der(&der)
            .context("parse the encrypted private key")?
            .decrypt(passphrase)
            .context("decrypt the private key")?
            .as_bytes()
            .to_vec(),
        "PRIVATE KEY" => der,
        other => anyhow::bail!("unexpected private key PEM label {other:?}"),
    };
    Ok(PrivateKeyDer::Pkcs8(key_der.into()))
}

fn record_expiry(key: &CertifiedKey, metrics: &ProxyMetrics) -> Result<()> {
    use x509_parser::prelude::FromDer;

    let leaf = key.end_entity_cert()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf)
        .context("parse the TLS leaf certificate")?;
    metrics
        .tls_cert_not_after
        .set(cert.validity().not_after.timestamp());
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    /// A self-signed `localhost` certificate and its key, as PEM files.
    pub(crate) struct TestCert {
        pub(crate) source: CertSource,
        _dir: tempfile::TempDir,
    }

    pub(crate) fn test_cert() -> TestCert {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        TestCert {
            source: CertSource::Files {
                cert: cert_path,
                key: key_path,
            },
            _dir: dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::test_cert;
    use super::*;

    fn served_leaf(cert: &ServerCert) -> CertificateDer<'static> {
        cert.current.read().unwrap().cert[0].clone()
    }

    #[tokio::test]
    async fn a_failed_reload_keeps_the_current_certificate() {
        let metrics = ProxyMetrics::new();
        let first = test_cert();
        let cert = ServerCert::load(&first.source, &metrics).await.unwrap();
        let leaf = served_leaf(&cert);

        let missing = CertSource::Files {
            cert: "/nonexistent/cert.pem".into(),
            key: "/nonexistent/key.pem".into(),
        };
        cert.reload(&missing, &metrics).await.unwrap_err();
        assert_eq!(served_leaf(&cert), leaf);

        let second = test_cert();
        cert.reload(&second.source, &metrics).await.unwrap();
        assert_ne!(served_leaf(&cert), leaf);
    }

    #[tokio::test]
    async fn refuses_a_key_that_does_not_match_the_certificate() {
        let (a, b) = (test_cert(), test_cert());
        let (CertSource::Files { cert, .. }, CertSource::Files { key, .. }) = (a.source, b.source)
        else {
            unreachable!()
        };
        let mismatched = CertSource::Files { cert, key };
        let error = ServerCert::load(&mismatched, &ProxyMetrics::new())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("does not match"), "{error:#}");
    }

    #[test]
    fn decrypts_a_key_encrypted_like_an_acm_export() {
        use pkcs8::der::Decode;
        use pkcs8::der::EncodePem;
        use pkcs8::pkcs5::pbes2;

        let key = rcgen::KeyPair::generate().unwrap();
        let passphrase = b"export-passphrase";
        // The scheme of the sample export in ACM's user guide.
        let params = pbes2::Parameters {
            kdf: pbes2::Pbkdf2Params {
                salt: &[7; 20],
                iteration_count: 2048,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha1,
            }
            .into(),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: &[9; 16] },
        };
        let encrypted = pkcs8::PrivateKeyInfo::from_der(&key.serialize_der())
            .unwrap()
            .encrypt_with_params(params, passphrase)
            .unwrap();
        let pem = pkcs8::EncryptedPrivateKeyInfo::from_der(encrypted.as_bytes())
            .unwrap()
            .to_pem(pkcs8::LineEnding::LF)
            .unwrap();

        let decrypted = decrypt_private_key(&pem, passphrase).unwrap();
        assert_eq!(decrypted.secret_der(), key.serialize_der().as_slice());
        decrypt_private_key(&pem, b"wrong").unwrap_err();
    }
}
