use std::sync::Arc;
use sui_http::rustls;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::CryptoProvider;
use rustls::crypto::{
    ring as provider, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::ServerName;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error,
    InconsistentKeys, PeerIncompatible, ServerConfig, SignatureScheme,
};

pub fn make_server_config(private_key: ed25519_dalek::SigningKey) -> rustls::ServerConfig {
    let server_private_key = provider::default_provider()
        .key_provider
        .load_private_key(
            PrivateKeyDer::try_from(private_key.to_pkcs8_der().unwrap().as_bytes())
                .expect("cannot open private key file")
                .clone_key(),
        )
        .expect("cannot load signing key");
    let server_public_key = server_private_key
        .public_key()
        .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))
        .expect("cannot load public key");
    let server_public_key_as_cert = CertificateDer::from(server_public_key.to_vec());

    let certified_key = Arc::new(CertifiedKey::new(
        vec![server_public_key_as_cert],
        server_private_key,
    ));

    // let server_cert_resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));
    let server_cert_resolver = Arc::new(X509OrRawPublicKey { x509: (), rpk: certified_key });

    ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_cert_resolver(server_cert_resolver)
}

pub fn make_client_config_no_verification() -> ClientConfig {
    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new(
            provider::default_provider(),
        )))
        .with_no_client_auth()
}

pub fn make_client_config(public_key: ed25519_dalek::VerifyingKey) -> ClientConfig {
    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerRpkVerifier::new_ed25519(public_key)))
        .with_no_client_auth()
}

#[derive(Debug)]
pub struct NoCertificateVerification(CryptoProvider);

impl NoCertificateVerification {
    pub fn new(provider: CryptoProvider) -> Self {
        Self(provider)
    }
}

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Verifies the tls handshake signature of the server,
/// and that the server's raw public key is in the list of trusted keys.
///
/// Note: when the verifier is used for Raw Public Keys the `CertificateDer` argument to the functions contains the SPKI instead of a X509 Certificate
#[derive(Debug)]
struct ServerRpkVerifier {
    trusted_spki: SubjectPublicKeyInfoDer<'static>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerRpkVerifier {
    fn new(trusted_spki: SubjectPublicKeyInfoDer<'static>) -> Self {
        Self {
            trusted_spki,
            supported_algs: provider::default_provider().signature_verification_algorithms,
        }
    }

    fn new_ed25519(public_key: ed25519_dalek::VerifyingKey) -> Self {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let trusted_spki =
            SubjectPublicKeyInfoDer::from(public_key.to_public_key_der().unwrap().into_vec());
        Self {
            trusted_spki,
            supported_algs: provider::default_provider().signature_verification_algorithms,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerRpkVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        if self.trusted_spki == end_entity_as_spki {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
struct X509OrRawPublicKey {
    x509: (), //Arc<CertifiedKey>,
    rpk: Arc<CertifiedKey>,
}

impl ResolvesServerCert for X509OrRawPublicKey {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.rpk.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}
