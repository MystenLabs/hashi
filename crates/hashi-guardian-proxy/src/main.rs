// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi_guardian_proxy::cache::CachingGuardianGrpc;
use hashi_guardian_proxy::config::Config;
use hashi_guardian_proxy::forward::Forwarding;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use tonic::transport::Endpoint;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_file_line(true)
        .with_env()
        .init();

    abort_on_panic();

    let config = Config::from_env()?;
    info!(
        backend = %config.backend_url,
        listen = %config.listen_addr,
        "Starting hashi-guardian-proxy (out-of-enclave wid-keyed cache + forwarder)."
    );

    // Lazy channel to the enclave guardian. Mirrors the node-side client
    // (crates/hashi/src/grpc/guardian_client.rs): connect lazily with the same
    // connect timeout + HTTP/2 keepalive.
    let channel = Endpoint::from_shared(config.backend_url.clone())?
        .connect_timeout(config.connect_timeout)
        .http2_keep_alive_interval(config.keepalive_interval)
        .connect_lazy();

    let svc = CachingGuardianGrpc::new(Forwarding::new(channel));

    // gRPC health service, mirroring the guardian — the ALB target group
    // health-checks `grpc.health.v1.Health/Check`.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<CachingGuardianGrpc<Forwarding>>>()
        .await;

    info!("gRPC proxy listening on {}.", config.listen_addr);
    Server::builder()
        .add_service(health_service)
        .add_service(GuardianServiceServer::new(svc))
        .serve(config.listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

/// Make any panic abort the process instead of unwinding. The wid-keyed cache
/// uses a std `Mutex` whose `.expect("cache mutex poisoned")` assumes a
/// poisoned lock is unreachable — true only if a panic aborts rather than
/// unwinds past the lock guard. (Same rationale as the enclave's `main`.)
fn abort_on_panic() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        std::process::abort();
    }));
}
