// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TLS for the node listener, which a TCP-passthrough load balancer fronts:
//! nodes present their registered TLS key as a client certificate, and an
//! ALB can't verify Ed25519 keys. The listener serves a certificate for the
//! node hostname: an exportable ACM certificate, re-exported as ACM renews it,
//! or PEM files.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::UnixTime;
use rustls::server::danger::ClientCertVerified;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::CertificateError;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::PeerIncompatible;
use rustls::SignatureScheme;
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
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(Arc::new(NodeCertVerifier::new()))
    .with_cert_resolver(cert))
}

/// The Ed25519 key of a node's self-signed TLS certificate.
pub fn node_tls_key(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use x509_parser::prelude::FromDer;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert).ok()?;
    let key = ed25519_dalek::VerifyingKey::from_public_key_der(cert.public_key().raw).ok()?;
    Some(key.to_bytes())
}

/// Requires a client certificate with an Ed25519 key, proven by the client's
/// TLS 1.3 signature. Nodes present self-signed certificates, so there is no
/// chain to check; which keys may call node RPCs is decided per request.
#[derive(Debug)]
struct NodeCertVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl NodeCertVerifier {
    fn new() -> Self {
        Self {
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for NodeCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        node_tls_key(end_entity).ok_or(rustls::Error::InvalidCertificate(
            CertificateError::BadEncoding,
        ))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
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

    let chain = exported_chain(
        exported
            .certificate()
            .context("ACM export returned no certificate")?,
        exported.certificate_chain(),
    )?;
    let key = decrypt_private_key(
        exported
            .private_key()
            .context("ACM export returned no private key")?,
        passphrase.as_bytes(),
    )?;
    Ok((chain, key))
}

/// The leaf followed by the export's chain, which excludes it.
fn exported_chain(leaf: &str, chain: Option<&str>) -> Result<Vec<CertificateDer<'static>>> {
    let pem = format!("{leaf}\n{}", chain.unwrap_or_default());
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parse the exported ACM certificate chain")?;
    // Clients don't fetch missing intermediates, so a leaf alone fails every handshake.
    anyhow::ensure!(
        chain.len() > 1,
        "ACM export returned no intermediate certificates"
    );
    Ok(chain)
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
        pub(crate) cert_pem: String,
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
            cert_pem: cert.pem(),
            source: CertSource::Files {
                cert: cert_path,
                key: key_path,
            },
            _dir: dir,
        }
    }

    /// The self-signed certificate a node presents with its TLS key.
    pub(crate) fn node_identity(key: &ed25519_dalek::SigningKey) -> tonic::transport::Identity {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let pkcs8 = key.to_pkcs8_der().unwrap();
        let key_pair = rcgen::KeyPair::from_der_and_sign_algo(
            &PrivateKeyDer::Pkcs8(pkcs8.as_bytes().to_vec().into()),
            &rcgen::PKCS_ED25519,
        )
        .unwrap();
        let cert = rcgen::CertificateParams::new(vec!["hashi".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        tonic::transport::Identity::from_pem(cert.pem(), key_pair.serialize_pem())
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

    #[tokio::test]
    async fn requires_an_ed25519_client_certificate() {
        use tonic::transport::Certificate;
        use tonic::transport::ClientTlsConfig;
        use tonic::transport::Endpoint;
        use tonic::transport::Identity;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::pb::HealthCheckRequest;

        let served = test_cert();
        let (reporter, health) = tonic_health::server::health_reporter();
        reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        let app = axum::Router::new().route_service("/grpc.health.v1.Health/{*rest}", health);
        let cert = ServerCert::load(&served.source, &ProxyMetrics::new())
            .await
            .unwrap();
        let server = sui_http::Builder::new()
            .tls_config(server_config(cert).unwrap())
            .serve("127.0.0.1:0", app)
            .unwrap();
        let check = |identity: Option<Identity>| {
            let mut tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&served.cert_pem))
                .domain_name("localhost");
            if let Some(identity) = identity {
                tls = tls.identity(identity);
            }
            let channel = Endpoint::from_shared(format!("https://{}", server.local_addr()))
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect_lazy();
            async move {
                HealthClient::new(channel)
                    .check(HealthCheckRequest {
                        service: String::new(),
                    })
                    .await
            }
        };

        let node = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        check(Some(test_utils::node_identity(&node))).await.unwrap();
        check(None).await.unwrap_err();
        // The listener asks only for Ed25519 signatures, so this client can't
        // send its certificate at all.
        let ecdsa = rcgen::KeyPair::generate().unwrap();
        let ecdsa_cert = rcgen::CertificateParams::new(vec!["hashi".to_string()])
            .unwrap()
            .self_signed(&ecdsa)
            .unwrap();
        check(Some(Identity::from_pem(
            ecdsa_cert.pem(),
            ecdsa.serialize_pem(),
        )))
        .await
        .unwrap_err();
    }

    #[test]
    fn reads_only_ed25519_certificate_keys() {
        let ed25519 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ecdsa = rcgen::KeyPair::generate().unwrap();
        let self_signed = |key: &rcgen::KeyPair| {
            rcgen::CertificateParams::new(vec!["hashi".to_string()])
                .unwrap()
                .self_signed(key)
                .unwrap()
                .der()
                .clone()
        };
        let expected: [u8; 32] = ed25519.public_key_raw().try_into().unwrap();
        assert_eq!(node_tls_key(&self_signed(&ed25519)), Some(expected));
        assert_eq!(node_tls_key(&self_signed(&ecdsa)), None);
    }

    #[test]
    fn an_acm_export_serves_its_leaf_first_and_needs_its_intermediates() {
        let pem = |name: &str| {
            let key = rcgen::KeyPair::generate().unwrap();
            rcgen::CertificateParams::new(vec![name.to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap()
                .pem()
        };
        let (leaf, intermediate) = (pem("leaf"), pem("intermediate"));

        let chain = exported_chain(&leaf, Some(&intermediate)).unwrap();
        assert_eq!(
            chain,
            [
                CertificateDer::from_pem_slice(leaf.as_bytes()).unwrap(),
                CertificateDer::from_pem_slice(intermediate.as_bytes()).unwrap(),
            ]
        );
        exported_chain(&leaf, None).unwrap_err();
        exported_chain(&leaf, Some("")).unwrap_err();
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
