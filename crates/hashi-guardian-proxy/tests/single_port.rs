// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy serves native gRPC and the plain-HTTP `/info` + `/health` on ONE
//! port, over TLS or, locally, plaintext. This guards the crux of that merge:
//! one server must dispatch both gRPC and HTTP/1.1 on the same socket.

use axum::routing::get;
use axum::Router;
use hashi_guardian_proxy::metrics::ProxyMetrics;
use hashi_guardian_proxy::tls;
use hashi_guardian_proxy::tls::CertSource;
use hashi_guardian_proxy::tls::ServerCert;
use tonic::transport::Certificate;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

/// Same shape as the proxy's router: a tonic gRPC service mounted as an axum
/// route-service, merged with a plain-HTTP GET route.
async fn router() -> Router {
    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    Router::new()
        .route_service("/grpc.health.v1.Health/{*rest}", health_service)
        .merge(Router::new().route("/health", get(|| async { axum::http::StatusCode::OK })))
}

async fn grpc_health(endpoint: Endpoint) -> ServingStatus {
    HealthClient::new(endpoint.connect().await.unwrap())
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .status()
}

#[tokio::test]
async fn grpc_and_http_share_one_tls_port() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let served = ServerCert::load(
        &CertSource::Files {
            cert: cert_path,
            key: key_path,
        },
        &ProxyMetrics::new(),
    )
    .await
    .unwrap();
    let server = sui_http::Builder::new()
        .tls_config(tls::server_config(served).unwrap())
        .serve("127.0.0.1:0", router().await)
        .unwrap();
    let addr = *server.local_addr();

    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(cert.pem()))
                .domain_name("localhost"),
        )
        .unwrap();
    assert_eq!(grpc_health(endpoint).await, ServingStatus::Serving);

    let response = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("localhost", addr)
        .http1_only()
        .build()
        .unwrap()
        .get(format!("https://localhost:{}/health", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_11);
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn grpc_and_http_share_one_plaintext_port() {
    let server = sui_http::Builder::new()
        .serve("127.0.0.1:0", router().await)
        .unwrap();
    let addr = *server.local_addr();

    let endpoint = Endpoint::from_shared(format!("http://{addr}")).unwrap();
    assert_eq!(grpc_health(endpoint).await, ServingStatus::Serving);

    let response = reqwest::get(format!("http://{addr}/health")).await.unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_11);
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
