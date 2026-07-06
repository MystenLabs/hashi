// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi_guardian_proxy::cache::CachingGuardianGrpc;
use hashi_guardian_proxy::config::Config;
use hashi_guardian_proxy::forward::Forwarding;
use hashi_guardian_proxy::relay::Relay;
use hashi_types::proto::guardian_relay_service_server::GuardianRelayServiceServer;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use tonic::transport::Endpoint;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing::info;
use tracing::warn;

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
        kp_roster = config.authorized_kp_fingerprints.len(),
        "Starting hashi-guardian-proxy (wid-keyed cache + node forwarder + provisioning relay)."
    );
    if config.authorized_kp_fingerprints.is_empty() {
        warn!(
            "AUTHORIZED_KP_FINGERPRINTS is empty: the provisioning relay will reject \
             all share submissions until a KP roster is configured."
        );
    }

    // Lazy channel to the enclave guardian, shared by forwarder and relay. Mirrors
    // the node-side client (crates/hashi/src/grpc/guardian_client.rs): same timeout + keepalive.
    let channel = Endpoint::from_shared(config.backend_url.clone())?
        .connect_timeout(config.connect_timeout)
        .http2_keep_alive_interval(config.keepalive_interval)
        .connect_lazy();

    let guardian_svc = CachingGuardianGrpc::new(Forwarding::new(channel.clone()));
    let relay_svc = Relay::new(channel, config.authorized_kp_fingerprints);

    // gRPC health service, mirroring the guardian — the ALB target group
    // health-checks `grpc.health.v1.Health/Check`.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<CachingGuardianGrpc<Forwarding>>>()
        .await;
    health_reporter
        .set_serving::<GuardianRelayServiceServer<Relay>>()
        .await;
    // An ALB gRPC health check queries the empty ("") service, so mark it
    // serving too — otherwise the target group flaps the proxy as unhealthy.
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    info!("gRPC proxy listening on {}.", config.listen_addr);
    Server::builder()
        .add_service(health_service)
        .add_service(GuardianServiceServer::new(guardian_svc))
        .add_service(GuardianRelayServiceServer::new(relay_svc))
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
