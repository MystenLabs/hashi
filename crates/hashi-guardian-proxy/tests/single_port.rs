// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy serves native gRPC and the plain-HTTP `/info` + `/health` on ONE
//! port. This guards the crux of that merge: one `axum::serve` must dispatch
//! both h2c gRPC and HTTP/1.1 on the same socket.

use axum::routing::get;
use axum::Router;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tonic::transport::Channel;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

#[tokio::test]
async fn grpc_and_http_share_one_port() {
    // Same shape as `main`: a tonic gRPC service mounted as an axum
    // route-service, merged with a plain-HTTP GET route, under one router.
    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    let router = Router::new()
        .route_service("/grpc.health.v1.Health/{*rest}", health_service)
        .merge(Router::new().route("/health", get(|| async { axum::http::StatusCode::OK })));

    // Bind first (the socket is listening before `serve` accepts), so a client
    // can connect with no startup race.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // (1) Native gRPC over h2c on the port: the health check returns SERVING.
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let status = HealthClient::new(channel)
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .status();
    assert_eq!(status, ServingStatus::Serving);

    // (2) Plain HTTP/1.1 GET on the SAME port: `/health` returns 200.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected HTTP 200 on the shared port, got: {resp}"
    );
}
