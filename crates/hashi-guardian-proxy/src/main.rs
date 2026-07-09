// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use hashi_guardian_proxy::cache::CachingGuardianGrpc;
use hashi_guardian_proxy::config::Config;
use hashi_guardian_proxy::forward::Forwarding;
use hashi_guardian_proxy::info;
use hashi_guardian_proxy::metrics::ProxyMetrics;
use hashi_guardian_proxy::relay::Relay;
use hashi_guardian_proxy::widlog::S3LogStore;
use hashi_types::proto::guardian_relay_service_server::GuardianRelayServiceServer;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Endpoint;
use tonic_health::server::health_reporter;
use tracing::error;
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
        log_bucket = %config.log_bucket,
        network = %config.btc_network,
        kp_roster = config.authorized_kp_fingerprints.len(),
        "Starting hashi-guardian-proxy (wid-keyed cache + node forwarder + provisioning relay)."
    );
    if config.authorized_kp_fingerprints.is_empty() {
        warn!(
            "AUTHORIZED_KP_FINGERPRINTS is empty: the provisioning relay will reject \
             all share submissions until a KP roster is configured."
        );
    }

    // The wid cache's durable tier. Prove bucket access before serving: a
    // proxy that can't read the log fails every retry closed.
    let log_store = S3LogStore::connect(config.log_bucket.clone(), config.log_region.clone()).await;
    probe_with_retries(&log_store).await?;

    let metrics = Arc::new(ProxyMetrics::new());
    tokio::spawn({
        let metrics = metrics.clone();
        let addr = config.metrics_listen_addr;
        async move {
            if let Err(e) = metrics.serve(addr).await {
                error!(error = %e, "Metrics server exited.");
            }
        }
    });

    // Lazy channel to the enclave guardian, shared by forwarder, relay, and the
    // /info reader. Mirrors the node-side client
    // (crates/hashi/src/grpc/guardian_client.rs): same timeout + keepalive.
    let channel = Endpoint::from_shared(config.backend_url.clone())?
        .connect_timeout(config.connect_timeout)
        .http2_keep_alive_interval(config.keepalive_interval)
        .connect_lazy();

    let guardian_svc = CachingGuardianGrpc::new(
        Forwarding::new(channel.clone()),
        log_store,
        config.btc_network,
        metrics.clone(),
    );
    let info_state = info::InfoState::new(
        GuardianServiceClient::new(channel.clone()),
        config.info_cache_ttl,
    );
    let relay_svc = Relay::new(channel, config.authorized_kp_fingerprints);

    // Standard gRPC health service (`grpc.health.v1.Health`) for gRPC
    // health-checkers; the HTTP `/health` route below covers plain-HTTP liveness.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<CachingGuardianGrpc<Forwarding, S3LogStore>>>()
        .await;
    health_reporter
        .set_serving::<GuardianRelayServiceServer<Relay>>()
        .await;
    // A gRPC health check may query the empty ("") service, so mark it serving
    // too — otherwise such a check flaps the proxy as unhealthy.
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    // Serve gRPC (forwarder + relay + health) and the HTTP `/info` + `/health` on
    // ONE port: each tonic service is mounted as an axum route-service, the plain
    // routes merged in, one `axum::serve`. Mirrors crates/hashi/src/grpc/mod.rs.
    let router = axum::Router::new()
        .add_grpc_service(health_service)
        .add_grpc_service(GuardianServiceServer::new(guardian_svc))
        .add_grpc_service(GuardianRelayServiceServer::new(relay_svc))
        .merge(info::router(info_state));

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("bind proxy server to {}", config.listen_addr))?;
    info!(
        "Proxy listening on {} (gRPC + HTTP /info + /health).",
        config.listen_addr
    );
    // If the accept loop dies, return so the supervisor restarts a clean task
    // rather than leaving the surface silently dead.
    axum::serve(listener, router)
        .await
        .map_err(|e| anyhow::anyhow!("proxy server error: {e}"))?;
    Ok(())
}

/// Mount a tonic gRPC service as an axum route-service at `/{ServiceName}/*`, so
/// gRPC and plain-HTTP routes share one router. Mirrors `crates/hashi/src/grpc/mod.rs`.
trait RouterExt {
    fn add_grpc_service<S>(self, svc: S) -> Self
    where
        S: tower::Service<
                axum::extract::Request,
                Response: axum::response::IntoResponse,
                Error = std::convert::Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static;
}

impl RouterExt for axum::Router {
    fn add_grpc_service<S>(self, svc: S) -> Self
    where
        S: tower::Service<
                axum::extract::Request,
                Response: axum::response::IntoResponse,
                Error = std::convert::Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.route_service(&format!("/{}/{{*rest}}", S::NAME), svc)
    }
}

/// Retry transient S3 blips at boot (no target-group crash-loop), but fail
/// fast on real misconfiguration (bad bucket, missing role).
async fn probe_with_retries(log_store: &S3LogStore) -> Result<()> {
    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match log_store.probe().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < ATTEMPTS => {
                warn!(attempt, error = %e, "Wid log bucket probe failed; retrying.");
                tokio::time::sleep(Duration::from_secs(2 * u64::from(attempt))).await;
            }
            Err(e) => return Err(e.context("wid log bucket is not readable")),
        }
    }
    unreachable!("loop returns on success or final error")
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
