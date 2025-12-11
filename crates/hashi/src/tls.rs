use std::sync::Arc;
use sui_http::rustls;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use rustls::CertificateError;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::Error;
use rustls::PeerIncompatible;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::crypto::CryptoProvider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::ring as provider;
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::UnixTime;
use rustls::version::TLS13;

const HASHI_SERVER_NAME: &str = "hashi";

pub fn make_server_config(private_key: ed25519_dalek::SigningKey) -> rustls::ServerConfig {
    let private_key_der = PrivateKeyDer::try_from(private_key.to_pkcs8_der().unwrap().as_bytes())
        .expect("cannot open private key file")
        .clone_key();
    let cert = generate_self_signed_tls_certificate(&private_key_der, HASHI_SERVER_NAME);

    ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(std::sync::Arc::new(ClientCertVerifier::new()))
        .with_single_cert(vec![cert], private_key_der)
        .unwrap()
}

pub fn make_client_config_no_verification() -> ClientConfig {
    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new(
            provider::default_provider(),
        )))
        .with_no_client_auth()
}

pub fn make_client_config(public_key: &ed25519_dalek::VerifyingKey) -> ClientConfig {
    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerCertVerifier::new_ed25519(public_key)))
        .with_no_client_auth()
}

pub fn make_client_config_with_client_auth(
    own_private_key: &ed25519_dalek::SigningKey,
    server_public_key: &ed25519_dalek::VerifyingKey,
) -> ClientConfig {
    let private_key_der =
        PrivateKeyDer::try_from(own_private_key.to_pkcs8_der().unwrap().as_bytes())
            .expect("cannot open private key file")
            .clone_key();
    let cert = generate_self_signed_tls_certificate(&private_key_der, HASHI_SERVER_NAME);

    ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ServerCertVerifier::new_ed25519(
            server_public_key,
        )))
        .with_client_auth_cert(vec![cert], private_key_der)
        .unwrap()
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
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Verifies the tls handshake signature of the server,
/// and that the server's public key is in the list of trusted keys.
#[derive(Debug)]
struct ServerCertVerifier {
    trusted_spki: SubjectPublicKeyInfoDer<'static>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier {
    fn new(trusted_spki: SubjectPublicKeyInfoDer<'static>) -> Self {
        Self {
            trusted_spki,
            supported_algs: provider::default_provider().signature_verification_algorithms,
        }
    }

    fn new_ed25519(public_key: &ed25519_dalek::VerifyingKey) -> Self {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let trusted_spki =
            SubjectPublicKeyInfoDer::from(public_key.to_public_key_der().unwrap().into_vec());
        Self::new(trusted_spki)
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let end_entity_as_spki = public_key_der_from_certificate(end_entity)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
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
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn generate_self_signed_tls_certificate(
    private_key: &PrivateKeyDer,
    server_name: &str,
) -> CertificateDer<'static> {
    let keypair =
        rcgen::KeyPair::from_der_and_sign_algo(private_key, &rcgen::PKCS_ED25519).unwrap();

    rcgen::CertificateParams::new(vec![server_name.to_owned()])
        .unwrap()
        .self_signed(&keypair)
        .expect(
            "unreachable! from_params should only fail if the key is incompatible with params.algo",
        )
        .der()
        .to_owned()
}

fn public_key_der_from_certificate<'a>(
    certificate: &'a CertificateDer,
) -> Result<SubjectPublicKeyInfoDer<'a>, anyhow::Error> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    let cert = X509Certificate::from_der(certificate.as_ref())
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    Ok(SubjectPublicKeyInfoDer::from(cert.1.subject_pki.raw))
}

pub fn public_key_from_certificate(
    certificate: &CertificateDer,
) -> Result<ed25519_dalek::VerifyingKey, anyhow::Error> {
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let spki = public_key_der_from_certificate(certificate)?;

    ed25519_dalek::VerifyingKey::from_public_key_der(spki.as_ref()).map_err(Into::into)
}

/// Verifies the tls handshake signature of the client,
/// and that the client's public key is ed25519.
#[derive(Debug)]
struct ClientCertVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier {
    pub(crate) fn new() -> Self {
        Self {
            supported_algs: provider::default_provider().signature_verification_algorithms,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for ClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        let _ed25519_public_key = public_key_from_certificate(end_entity)
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
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
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
